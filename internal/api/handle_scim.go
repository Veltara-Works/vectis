package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/scim"
)

// scimUserRequest is the inbound SCIM User body for create/replace. Active is a
// pointer so an omitted "active" can default to true (created enabled) rather
// than decoding to a zero-value false.
type scimUserRequest struct {
	Schemas     []string     `json:"schemas"`
	ExternalID  string       `json:"externalId"`
	UserName    string       `json:"userName"`
	Name        *scim.Name   `json:"name"`
	DisplayName string       `json:"displayName"`
	Active      *bool        `json:"active"`
	Emails      []scim.Email `json:"emails"`
}

// writeSCIMJSON encodes v as application/scim+json with the given status.
func writeSCIMJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scim.ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// scimBaseURL returns the absolute base for SCIM meta.location: the configured
// callback base URL, or the request host as a fallback.
func (s *Server) scimBaseURL(r *http.Request) string {
	if s.callbackBaseURL != "" {
		return strings.TrimRight(s.callbackBaseURL, "/")
	}
	return "https://" + r.Host
}

// scimUserResponse maps a mailbox to a SCIM User, resolving its domain name.
func (s *Server) scimUserResponse(ctx context.Context, m *repository.Mailbox, baseURL string) (scim.User, error) {
	d, err := s.domains.GetByID(ctx, m.DomainID)
	if err != nil {
		return scim.User{}, err
	}
	name := ""
	if d != nil {
		name = d.Name
	}
	return scim.MailboxToUser(m, name, baseURL), nil
}

func displayNameFromReq(req scimUserRequest) *string {
	if req.DisplayName != "" {
		dn := req.DisplayName
		return &dn
	}
	if req.Name != nil && req.Name.Formatted != "" {
		dn := req.Name.Formatted
		return &dn
	}
	return nil
}

// randomMailboxPassword returns a 64-hex-char random string. SCIM-provisioned
// mailboxes authenticate via SSO, not IMAP basic-auth, so this only satisfies
// the NOT NULL password_hash; it is hashed and never returned.
func randomMailboxPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// --- Discovery -------------------------------------------------------------

func (s *Server) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, scim.DefaultServiceProviderConfig(s.scimBaseURL(r)))
}

func (s *Server) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, scim.UserResourceTypesResponse(s.scimBaseURL(r)))
}

func (s *Server) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	writeSCIMJSON(w, http.StatusOK, scim.UserSchemasResponse())
}

// --- Users -----------------------------------------------------------------

func (s *Server) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", "Malformed SCIM JSON: "+err.Error())
		return
	}
	if req.UserName == "" {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	localPart, domainName, err := scim.SplitUserName(req.UserName)
	if err != nil {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if !validLocalPartRe.MatchString(localPart) || len(localPart) > 64 {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", "Invalid local part in userName")
		return
	}

	domain, err := s.domains.GetByName(r.Context(), domainName)
	if err != nil {
		s.logger.Error("scim: domain lookup failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if domain == nil {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue",
			"Domain "+domainName+" is not provisioned on this server")
		return
	}
	if !domain.Active {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", "Domain "+domainName+" is not active")
		return
	}

	// Idempotency: an externalId or (domain, localPart) collision is a 409. A DB
	// error here must surface as a clean 500 — not fall through to a create that
	// would fail later with a misleading error (or skip the uniqueness guard).
	if req.ExternalID != "" {
		existing, lerr := s.mailboxes.GetByExternalID(r.Context(), req.ExternalID)
		if lerr != nil {
			s.logger.Error("scim: externalId lookup failed", "error", lerr)
			scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
			return
		}
		if existing != nil {
			scim.WriteError(w, http.StatusConflict, "uniqueness", "A user with this externalId already exists")
			return
		}
	}
	existing, lerr := s.mailboxes.GetByEmail(r.Context(), domain.ID, localPart)
	if lerr != nil {
		s.logger.Error("scim: userName lookup failed", "error", lerr)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if existing != nil {
		scim.WriteError(w, http.StatusConflict, "uniqueness", "A user with userName "+req.UserName+" already exists")
		return
	}

	pw, err := randomMailboxPassword()
	if err != nil {
		s.logger.Error("scim: password generation failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.logger.Error("scim: password hash failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}

	create := repository.MailboxCreate{
		DomainID:     domain.ID,
		LocalPart:    localPart,
		PasswordHash: hash,
		DisplayName:  displayNameFromReq(req),
	}
	if req.ExternalID != "" {
		create.ExternalID = &req.ExternalID
	}
	m, err := s.mailboxes.Create(r.Context(), create)
	if err != nil {
		s.logger.Error("scim: create mailbox failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Failed to create user")
		return
	}

	// Mailboxes are created active; honour an explicit active:false on create.
	if req.Active != nil && !*req.Active {
		inactive := false
		if updated, uerr := s.mailboxes.Update(r.Context(), m.ID, repository.MailboxUpdate{Active: &inactive}); uerr == nil && updated != nil {
			m = updated
		}
	}

	s.provisionMaildir(domain.Name, localPart)

	user := scim.MailboxToUser(m, domain.Name, s.scimBaseURL(r))
	w.Header().Set("Location", user.Meta.Location)
	writeSCIMJSON(w, http.StatusCreated, user)
}

func (s *Server) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	baseURL := s.scimBaseURL(r)
	var users []scim.User

	if value, ok := scim.ParseUserNameFilter(r.URL.Query().Get("filter")); ok {
		if localPart, domainName, err := scim.SplitUserName(value); err == nil {
			// A DB error must surface as a 500, not a silent empty ListResponse —
			// an empty result tells the IdP "no such user" and provokes a create.
			domain, derr := s.domains.GetByName(r.Context(), domainName)
			if derr != nil {
				s.logger.Error("scim: filter domain lookup failed", "error", derr)
				scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
				return
			}
			if domain != nil {
				m, merr := s.mailboxes.GetByEmail(r.Context(), domain.ID, localPart)
				if merr != nil {
					s.logger.Error("scim: filter mailbox lookup failed", "error", merr)
					scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
					return
				}
				if m != nil {
					users = append(users, scim.MailboxToUser(m, domain.Name, baseURL))
				}
			}
		}
	}
	// No filter or an unsupported filter yields an empty ListResponse (not a
	// 404 — Okta treats 404 on a filter as a fatal config error). Full no-filter
	// sync is Phase 2.
	writeSCIMJSON(w, http.StatusOK, scim.NewListResponse(users))
}

func (s *Server) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	m, err := s.mailboxes.GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.logger.Error("scim: get mailbox failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if m == nil {
		scim.WriteError(w, http.StatusNotFound, "", "User not found")
		return
	}
	user, err := s.scimUserResponse(r.Context(), m, s.scimBaseURL(r))
	if err != nil {
		s.logger.Error("scim: resolve domain failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	writeSCIMJSON(w, http.StatusOK, user)
}

func (s *Server) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", "Malformed SCIM JSON: "+err.Error())
		return
	}
	m, err := s.mailboxes.GetByID(r.Context(), id)
	if err != nil {
		s.logger.Error("scim: get mailbox failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if m == nil {
		scim.WriteError(w, http.StatusNotFound, "", "User not found")
		return
	}

	domain, _ := s.domains.GetByID(r.Context(), m.DomainID)
	domainName := ""
	if domain != nil {
		domainName = domain.Name
	}
	// userName is immutable in Phase 1 — mailboxes have no rename primitive.
	if req.UserName != "" && req.UserName != m.LocalPart+"@"+domainName {
		scim.WriteError(w, http.StatusConflict, "mutability", "Changing userName is not supported in this version")
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}
	updated, err := s.mailboxes.Update(r.Context(), id, repository.MailboxUpdate{
		DisplayName: displayNameFromReq(req),
		Active:      &active,
	})
	if err != nil {
		s.logger.Error("scim: update mailbox failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if updated == nil {
		scim.WriteError(w, http.StatusNotFound, "", "User not found")
		return
	}
	writeSCIMJSON(w, http.StatusOK, scim.MailboxToUser(updated, domainName, s.scimBaseURL(r)))
}

func (s *Server) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req scim.PatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", "Malformed SCIM JSON: "+err.Error())
		return
	}
	m, err := s.mailboxes.GetByID(r.Context(), id)
	if err != nil {
		s.logger.Error("scim: get mailbox failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if m == nil {
		scim.WriteError(w, http.StatusNotFound, "", "User not found")
		return
	}

	active, found, perr := scim.ExtractActiveChange(req)
	if perr != nil {
		scim.WriteError(w, http.StatusBadRequest, "invalidValue", perr.Error())
		return
	}
	if found {
		updated, uerr := s.mailboxes.Update(r.Context(), id, repository.MailboxUpdate{Active: active})
		if uerr != nil {
			s.logger.Error("scim: update mailbox failed", "error", uerr)
			scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
			return
		}
		if updated != nil {
			m = updated
		}
	}

	user, err := s.scimUserResponse(r.Context(), m, s.scimBaseURL(r))
	if err != nil {
		s.logger.Error("scim: resolve domain failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	writeSCIMJSON(w, http.StatusOK, user)
}

func (s *Server) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	m, err := s.mailboxes.GetByID(r.Context(), id)
	if err != nil {
		s.logger.Error("scim: get mailbox failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	if m == nil {
		scim.WriteError(w, http.StatusNotFound, "", "User not found")
		return
	}
	// Locked decision: DELETE deactivates, never erases (avoids orphaning mail
	// and conflicting with DSAR erasure tombstones). Erasure stays a deliberate
	// DSAR action.
	inactive := false
	if _, err := s.mailboxes.Update(r.Context(), id, repository.MailboxUpdate{Active: &inactive}); err != nil {
		s.logger.Error("scim: deactivate mailbox failed", "error", err)
		scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
