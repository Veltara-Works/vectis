package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

type verifyDomainResponse struct {
	Domain             string `json:"domain"`
	VerificationStatus string `json:"verification_status"`
	VerificationToken  string `json:"verification_token,omitempty"`
	TXTRecordName      string `json:"txt_record_name"`
	TXTRecordValue     string `json:"txt_record_value"`
	Found              bool   `json:"found"`
}

// handleVerifyDomain performs a DNS TXT lookup to verify domain ownership.
// The domain must have a TXT record containing the verification token.
func (s *Server) handleVerifyDomain(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "DOMAIN_NOT_FOUND", "Domain not found")
		return
	}

	if domain.VerificationToken == nil || *domain.VerificationToken == "" {
		respondError(w, r, http.StatusBadRequest, "NO_VERIFICATION_TOKEN", "Domain has no verification token")
		return
	}

	if domain.VerificationStatus == "verified" {
		respond(w, r, http.StatusOK, verifyDomainResponse{
			Domain:             domain.Name,
			VerificationStatus: "verified",
			TXTRecordName:      domain.Name,
			TXTRecordValue:     *domain.VerificationToken,
			Found:              true,
		})
		return
	}

	// Perform DNS TXT lookup.
	txtRecords, err := net.LookupTXT(domain.Name)
	if err != nil {
		// DNS lookup failure is not a server error — the record just doesn't exist yet.
		s.logger.Info("DNS TXT lookup failed", "domain", domain.Name, "error", err)
	}

	found := false
	for _, record := range txtRecords {
		if strings.TrimSpace(record) == *domain.VerificationToken {
			found = true
			break
		}
	}

	newStatus := "pending"
	if found {
		newStatus = "verified"
	}

	// Update verification status.
	if domain.VerificationStatus != newStatus {
		_, err = s.domains.Update(r.Context(), domainID, repository.DomainUpdate{
			VerificationStatus: &newStatus,
		})
		if err != nil {
			s.logger.Error("update verification status failed", "error", err)
			// Non-fatal — return the check result anyway.
		}
	}

	// Audit log on verification success.
	if found && domain.VerificationStatus != "verified" {
		adminID := getAdminID(r.Context())
		s.audit.Log(r.Context(), &adminID, "domain.verify", "domain", &domainID,
			map[string]any{"domain": domain.Name, "status": "verified"}, nil)
	}

	respond(w, r, http.StatusOK, verifyDomainResponse{
		Domain:             domain.Name,
		VerificationStatus: newStatus,
		VerificationToken:  *domain.VerificationToken,
		TXTRecordName:      domain.Name,
		TXTRecordValue:     *domain.VerificationToken,
		Found:              found,
	})
}
