package api

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/dkim"
	"github.com/Veltara-Works/vectis/internal/repository"
)

type dkimResponse struct {
	DNSName  string `json:"dns_name"`
	DNSValue string `json:"dns_value"`
	Selector string `json:"selector"`
	KeyPath  string `json:"key_path"`
}

type deliverabilityResponse struct {
	Domain string                    `json:"domain"`
	Checks []deliverabilityCheck     `json:"checks"`
}

type deliverabilityCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // "pass", "fail", "warn", "info"
	Value   string `json:"value,omitempty"`
	Hint    string `json:"hint,omitempty"`
}

func (s *Server) handleGenerateDKIM(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	selector := dkim.DefaultSelector()
	kp, err := dkim.GenerateKey(s.dkimBasePath, domain.Name, selector)
	if err != nil {
		s.logger.Error("generate DKIM key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate DKIM key")
		return
	}

	// Update domain with new DKIM key info.
	keyPath := kp.KeyPath
	_, err = s.domains.Update(r.Context(), domainID, repository.DomainUpdate{
		DKIMSelector: &selector,
		DKIMKeyPath:  &keyPath,
	})
	if err != nil {
		s.logger.Error("update domain DKIM failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Key generated but failed to update domain record")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "dkim.generate", "domain", &domainID,
		map[string]string{"selector": selector, "domain": domain.Name}, &ip)

	respond(w, r, http.StatusOK, dkimResponse{
		DNSName:  kp.DNSName(),
		DNSValue: kp.DNSRecord(),
		Selector: selector,
		KeyPath:  kp.KeyPath,
	})
}

func (s *Server) handleGetDKIM(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	if domain.DKIMKeyPath == nil || *domain.DKIMKeyPath == "" {
		respondError(w, r, http.StatusNotFound, "DKIM_NOT_CONFIGURED",
			"DKIM keys have not been generated for this domain. Use POST /domains/:id/dkim/generate")
		return
	}

	pubDER, err := dkim.ReadPublicKey(*domain.DKIMKeyPath)
	if err != nil {
		s.logger.Error("read DKIM key failed", "error", err, "path", *domain.DKIMKeyPath)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read DKIM key")
		return
	}

	dnsName := fmt.Sprintf("%s._domainkey.%s", domain.DKIMSelector, domain.Name)
	dnsValue := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(pubDER))

	respond(w, r, http.StatusOK, dkimResponse{
		DNSName:  dnsName,
		DNSValue: dnsValue,
		Selector: domain.DKIMSelector,
		KeyPath:  *domain.DKIMKeyPath,
	})
}

func (s *Server) handleRotateDKIM(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	// New selector for rotation.
	newSelector := dkim.DefaultSelector() + "r"

	kp, err := dkim.GenerateKey(s.dkimBasePath, domain.Name, newSelector)
	if err != nil {
		s.logger.Error("rotate DKIM key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate new DKIM key")
		return
	}

	keyPath := kp.KeyPath
	_, err = s.domains.Update(r.Context(), domainID, repository.DomainUpdate{
		DKIMSelector: &newSelector,
		DKIMKeyPath:  &keyPath,
	})
	if err != nil {
		s.logger.Error("update domain DKIM failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Key generated but failed to update domain record")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "dkim.rotate", "domain", &domainID,
		map[string]string{"old_selector": domain.DKIMSelector, "new_selector": newSelector}, &ip)

	respond(w, r, http.StatusOK, dkimResponse{
		DNSName:  kp.DNSName(),
		DNSValue: kp.DNSRecord(),
		Selector: newSelector,
		KeyPath:  kp.KeyPath,
	})
}

func (s *Server) handleDeliverability(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	var checks []deliverabilityCheck

	// MX record check
	mxRecords, err := net.LookupMX(domain.Name)
	if err != nil || len(mxRecords) == 0 {
		checks = append(checks, deliverabilityCheck{
			Name:   "MX",
			Status: "fail",
			Hint:   fmt.Sprintf("No MX record found for %s. Add: %s MX 10 %s", domain.Name, domain.Name, s.hostname),
		})
	} else {
		hosts := make([]string, 0, len(mxRecords))
		for _, mx := range mxRecords {
			hosts = append(hosts, strings.TrimSuffix(mx.Host, "."))
		}
		checks = append(checks, deliverabilityCheck{
			Name:   "MX",
			Status: "pass",
			Value:  strings.Join(hosts, ", "),
		})
	}

	// SPF record check
	txtRecords, _ := net.LookupTXT(domain.Name)
	spfFound := false
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			spfFound = true
			checks = append(checks, deliverabilityCheck{
				Name:   "SPF",
				Status: "pass",
				Value:  txt,
			})
			break
		}
	}
	if !spfFound {
		checks = append(checks, deliverabilityCheck{
			Name:   "SPF",
			Status: "fail",
			Hint:   fmt.Sprintf("No SPF record found. Add TXT: %s", dkim.SPFRecord("")),
		})
	}

	// DKIM record check
	if domain.DKIMKeyPath != nil && *domain.DKIMKeyPath != "" {
		dkimHost := fmt.Sprintf("%s._domainkey.%s", domain.DKIMSelector, domain.Name)
		dkimTxt, _ := net.LookupTXT(dkimHost)
		dkimFound := false
		for _, txt := range dkimTxt {
			if strings.Contains(txt, "v=DKIM1") {
				dkimFound = true
				checks = append(checks, deliverabilityCheck{
					Name:   "DKIM",
					Status: "pass",
					Value:  fmt.Sprintf("%s (selector: %s)", dkimHost, domain.DKIMSelector),
				})
				break
			}
		}
		if !dkimFound {
			checks = append(checks, deliverabilityCheck{
				Name:   "DKIM",
				Status: "fail",
				Hint:   fmt.Sprintf("No DKIM record at %s. Add the TXT record from GET /domains/%s/dkim", dkimHost, domainID),
			})
		}
	} else {
		checks = append(checks, deliverabilityCheck{
			Name:   "DKIM",
			Status: "warn",
			Hint:   "DKIM keys not generated. Use POST /domains/:id/dkim/generate",
		})
	}

	// DMARC record check
	dmarcTxt, _ := net.LookupTXT("_dmarc." + domain.Name)
	dmarcFound := false
	for _, txt := range dmarcTxt {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarcFound = true
			checks = append(checks, deliverabilityCheck{
				Name:   "DMARC",
				Status: "pass",
				Value:  txt,
			})
			break
		}
	}
	if !dmarcFound {
		checks = append(checks, deliverabilityCheck{
			Name:   "DMARC",
			Status: "fail",
			Hint:   fmt.Sprintf("No DMARC record. Add TXT at _dmarc.%s: %s", domain.Name, dkim.DMARCRecord(domain.Name)),
		})
	}

	// TXT verification auto-check: if domain is not yet verified, check if the
	// verification token is present in TXT records and auto-verify.
	if domain.VerificationStatus != "verified" && domain.VerificationToken != nil && *domain.VerificationToken != "" {
		verifyFound := false
		for _, txt := range txtRecords {
			if strings.TrimSpace(txt) == *domain.VerificationToken {
				verifyFound = true
				break
			}
		}
		if verifyFound {
			verified := "verified"
			s.domains.Update(r.Context(), domainID, repository.DomainUpdate{VerificationStatus: &verified})
			checks = append(checks, deliverabilityCheck{
				Name:   "Verification",
				Status: "pass",
				Value:  "Domain ownership verified via TXT record",
			})
		} else {
			checks = append(checks, deliverabilityCheck{
				Name:   "Verification",
				Status: "warn",
				Hint:   fmt.Sprintf("Domain not verified. Add TXT record: %s", *domain.VerificationToken),
			})
		}
	} else if domain.VerificationStatus == "verified" {
		checks = append(checks, deliverabilityCheck{
			Name:   "Verification",
			Status: "pass",
			Value:  "Domain ownership verified",
		})
	}

	// PTR record check (reverse DNS)
	addrs, _ := net.LookupHost(s.hostname)
	if len(addrs) > 0 {
		names, _ := net.LookupAddr(addrs[0])
		if len(names) > 0 {
			checks = append(checks, deliverabilityCheck{
				Name:   "PTR",
				Status: "pass",
				Value:  fmt.Sprintf("%s → %s", addrs[0], strings.TrimSuffix(names[0], ".")),
			})
		} else {
			checks = append(checks, deliverabilityCheck{
				Name:   "PTR",
				Status: "warn",
				Hint:   fmt.Sprintf("No PTR record for %s. Ask your hosting provider to set it to %s", addrs[0], s.hostname),
			})
		}
	}

	respond(w, r, http.StatusOK, deliverabilityResponse{
		Domain: domain.Name,
		Checks: checks,
	})
}
